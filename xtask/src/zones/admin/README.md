# Admin commands

`tempo-xtask admin` contains one-off operational commands for deployed Tempo
Zones:

- `admin check`: read-only cluster health and consistency checks
- `admin leader set`: guarded `zone_setLeader` handoff
- `admin identity prepare`: generate independent per-node P2P and sequencer keys
- `admin sequencer-set replace`: guarded one-for-one Portal membership replacement
- `admin encryption-key prepare`: generate a replacement shared key and a
  two-key decryption file
- `admin encryption-key register`: verify preloading, simulate, and optionally
  submit `setSequencerEncryptionKey`

These commands do not manage secrets or deployments. The recovery runbook owns
secret-manager changes, rolling restarts, deposit tests, rollback decisions,
and removal of the old key after the Portal grace period.

## Configuration

Admin commands accept an optional TOML file containing public inputs:

```toml
[zone]
id = 1
# Optional. Relative paths are resolved from this file's directory.
manifest = "./zone-manifest.toml"

[l1]
rpc_url = "https://tempo-rpc.example"
# Optional. Defaults to the repository's Moderato ZoneFactory.
zone_factory = "0x..."
# Optional assertion against the ZoneFactory mapping.
portal = "0x..."

[[nodes]]
name = "leader"
operator_rpc_url = "http://leader.internal:8545"

[[nodes]]
name = "follower"
operator_rpc_url = "http://follower.internal:8545"
```

The same values can be passed with `--zone-id`, `--zone-manifest`,
`--l1-rpc-url`, `--zone-factory`, `--portal`, and repeated `--operator-rpc`
arguments. CLI values override the file. Supplying any `--operator-rpc`
arguments replaces the file's complete node list.

## Health checks and leader handoffs

```bash
tempo-xtask admin check --config zone-admin.toml

tempo-xtask admin check \
  --config zone-admin.toml \
  --wait-ready --node follower --timeout 5m

tempo-xtask admin leader set \
  --config zone-admin.toml \
  --target follower --via leader

# Repeat only after reviewing the dry run.
tempo-xtask admin leader set \
  --config zone-admin.toml \
  --target follower --via leader --execute
```

`admin check` compares a finalized ZonePortal snapshot with all configured
operator RPCs. It checks identity, loaded topology, membership, finalized
leader agreement, promotion readiness, active decryption-key availability,
canonical state, lag against both the newest Zone node and finalized L1, and
Zone progress. When a manifest is supplied, every manifest identity must be
queried exactly once. RPC-only nodes are excluded from checks that require
sequencer keys or promotion readiness.

More specifically, the command:

1. Resolves the ZonePortal through ZoneFactory and reads all Portal state at one
   finalized Tempo block.
2. Queries every operator RPC concurrently.
3. Checks Zone and Portal identity, endpoint labels, live quorum membership,
   topology, finalized leader agreement, and promotion readiness on
   non-RPC-only sequencer nodes. RPC-only nodes cannot be promoted and are
   reported as `N/A` for readiness.
4. Verifies the active shared decryption key on non-RPC-only sequencer nodes.
   RPC-only nodes do not hold that key and are reported as `N/A`.
5. Fails when any node's local Zone height is more than 240 blocks (about two
   minutes) behind the newest node, or its Tempo anchor is more than 240 blocks
   behind finalized L1. It then compares block hash and state root across all
   nodes at their lowest common available Zone height.
6. Reports the finalized L1 batch index and settled Zone height. A new L1 batch
   is not required during the short observation window.
7. Samples the operator nodes again after `--observe-for` and verifies that each
   local Zone height advanced.
8. Applies any explicit `--require-*` assertions and, when supplied, compares
   the expected Zone manifest with the Portal and live nodes.

`--wait-ready --node <name>` is the post-restart primitive. It waits for that
node to become reachable, canonical, and promotion-ready when applicable.

`admin leader set` is a dry run unless `--execute` is supplied. Its target must
differ from the current finalized Portal leader; choose a different,
promotion-ready follower. Use `--via` when more than one configured sequencer
can relay the request.
During a one-for-one membership rollout, use `--rolling-membership` together
with `--zone-manifest <next-manifest>` only for the handoff that lets the old
leader restart. This permits expected old/new loaded-manifest disagreements
while still requiring both the target and `--via` relay to have loaded the
finalized Portal set and supplied next manifest. The rotated target can relay
its own handoff; alternatively, use a retained follower that already runs the
next manifest. The old-manifest leader cannot resolve a replacement identity.
The execute path waits for finalized leadership and target agreement, then
returns so the former leader can restart immediately. The full cluster check
supplies the progress and settlement gate.

## Shared-key rotation

Prepare creates two owner-readable secret files:

```text
<rotation-dir>/
  new-shared.key
  deposit-decryption-keys
```

```bash
tempo-xtask admin encryption-key prepare \
  --config zone-admin.toml \
  --current-key-file /secure/current-shared.key \
  --existing-decryption-keys-file /secure/deployed/deposit-decryption-keys \
  --rotation-dir /secure/rotation
```

The command checks the cluster, verifies that the supplied current key matches
the finalized Portal key, and verifies that the deployed decryption-key file
contains that active key. It generates a distinct replacement and writes a
merged `deposit-decryption-keys` file containing every distinct deployed key
plus the replacement. It refuses to overwrite either output unless `--force`
is supplied.

Deploy the merged `deposit-decryption-keys` output, then roll all potential
leaders before running registration without `--execute`:

```bash
tempo-xtask admin encryption-key register \
  --config zone-admin.toml \
  --new-key-file /secure/rotation/new-shared.key \
  --transaction-key-file /secure/individual-sequencer.key
```

This is both the preload gate and the transaction dry run. It requires every
non-RPC-only sequencer to report both the current Portal key and replacement
key, checks cluster health and signer membership, and simulates the exact
Portal call.

Submit only after reviewing the dry run:

```bash
tempo-xtask admin encryption-key register \
  --config zone-admin.toml \
  --new-key-file /secure/rotation/new-shared.key \
  --transaction-key-file /secure/individual-sequencer.key \
  --execute
```

The execute path repeats all checks immediately before submission and waits
until the replacement is the finalized active Portal key. It is safe to retry:
before submitting, the command checks the latest Portal state. If the replacement
key is included but not finalized, it waits instead of appending the key again. A
post-submission timeout includes the successful transaction hash.

After registration, use the normal `tempo-xtask deposit` command for the
decryption test. Then update `--sequencer-key-file`, roll nodes follower-first,
run `admin check`, and send a second deposit. Retain every grace-valid or
draining decryption key in the deployed keyring. Retire a specific old key only
after its Portal expiry and the deposit queue have drained.
run `admin check`, and send a second deposit. Retain every grace-valid or
draining decryption key in the deployed keyring. Retire a specific old key only
after its Portal expiry and the deposit queue have drained.

## Individual identity rotation

Generate a node's independent Ed25519 P2P key and secp256k1 sequencer key:

```bash
tempo-xtask admin identity prepare \
  --node node-a \
  --rotation-dir /secure/rotation/node-a
```

The command writes owner-only `p2p.key` and `sequencer.key` files and prints
only their public identities. It refuses to overwrite either output unless
`--force` is supplied.

After preparing a next-version manifest containing those public identities,
dry-run the exact one-for-one Portal replacement:

```bash
tempo-xtask admin sequencer-set replace \
  --config zone-admin.toml \
  --next-manifest next-zone-manifest.toml \
  --old-member 0x... \
  --new-member 0x... \
  --transaction-key-file /secure/portal-admin.key \
  --expected-version 12
```

The command requires the transaction signer to be the finalized Portal admin,
retains the threshold and active leader, verifies exact next-manifest
membership and version 13, and simulates `setSequencerSet`. Repeat with
`--execute` only after reviewing the report.
