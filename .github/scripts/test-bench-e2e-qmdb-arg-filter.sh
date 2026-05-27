#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

write_fake_tempo() {
  local path="$1"
  local state_root_help="${2:-}"
  cat > "$path" <<EOF
#!/usr/bin/env bash
set -euo pipefail

if [[ "\${1:-}" == "node" && "\${2:-}" == "--help" ]]; then
  cat <<'HELP'
--ipcdisable
--disable-discovery
--trusted-only
--tempo.bootnodes-endpoint <URL>
--consensus.no-legacy-archive
$state_root_help
HELP
  exit 0
fi

exit 1
EOF
  chmod +x "$path"
}

baseline_tempo="$tmpdir/baseline-tempo"
feature_tempo="$tmpdir/feature-tempo"
write_fake_tempo "$baseline_tempo"
write_fake_tempo "$feature_tempo" "--state-root.backend <BACKEND>"

BASELINE_TEMPO="$baseline_tempo" FEATURE_TEMPO="$feature_tempo" nu -c '
source bench-e2e.nu

let baseline = (e2e-supported-node-args $env.BASELINE_TEMPO qmdb)
let feature = (e2e-supported-node-args $env.FEATURE_TEMPO qmdb)

if "--state-root.backend" in $baseline.supported {
    error make { msg: "baseline kept unsupported --state-root.backend" }
}

if not ("--state-root.backend" in $baseline.removed) {
    error make { msg: "baseline did not report removed --state-root.backend" }
}

if not ("--state-root.backend" in $feature.supported) {
    error make { msg: "feature did not keep supported --state-root.backend" }
}

if "--state-root.backend" in $feature.removed {
    error make { msg: "feature reported supported --state-root.backend as removed" }
}
'

mpt_datadir="$tmpdir/tempo_e2e_1000mb"
qmdb_datadir="$tmpdir/tempo_e2e_1000mb_qmdb"
for datadir in "$mpt_datadir" "$qmdb_datadir"; do
  mkdir -p "$datadir/.bench-meta" "$datadir/db" "$datadir/static_files"
  touch \
    "$datadir/.bench-meta/genesis.json" \
    "$datadir/.bench-meta/trusted-peers.txt" \
    "$datadir/.bench-meta/marker.json" \
    "$datadir/signing.key" \
    "$datadir/signing.share" \
    "$datadir/enode.key" \
    "$datadir/enode.identity"
done
printf 'tempo-localnet-signing-key-secret\n' > "$qmdb_datadir/signing.secret"

MPT_DATADIR="$mpt_datadir" QMDB_DATADIR="$qmdb_datadir" nu -c '
source bench-e2e.nu

let mpt_missing = (e2e-snapshot-missing-files $env.MPT_DATADIR)
if (($mpt_missing | where { |path| $path | str ends-with "signing.secret" }) | length) != 0 {
    error make { msg: "mpt snapshot should not require signing.secret" }
}

let qmdb_missing = (e2e-snapshot-missing-files $env.QMDB_DATADIR)
if ($qmdb_missing | length) != 0 {
    error make { msg: "qmdb snapshot unexpectedly missing files" }
}

let mpt_args = (build-e2e-consensus-args $env.MPT_DATADIR "enode://local@127.0.0.1:1" 8000 "127.0.0.2")
if "--consensus.secret" in $mpt_args {
    error make { msg: "mpt args should not include absent consensus secret" }
}

let qmdb_args = (build-e2e-consensus-args $env.QMDB_DATADIR "enode://local@127.0.0.1:1" 8000 "127.0.0.2")
if not ("--consensus.secret" in $qmdb_args) {
    error make { msg: "qmdb args should include consensus secret" }
}
'
